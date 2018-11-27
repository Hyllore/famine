/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmapi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/11/27 18:28:20 by amaindro          #+#    #+#             */
/*   Updated: 2015/12/04 16:24:31 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	*ft_strmapi(const char *s, char (*f)(unsigned int, char))
{
	int		i;
	char	*s2;

	i = 0;
	s2 = malloc(sizeof(char) * (ft_strlen(s) + 1));
	if (s2)
	{
		while (s[i] != '\0')
		{
			s2[i] = f(i, s[i]);
			i++;
		}
		s2[i] = '\0';
		return (s2);
	}
	return (NULL);
}
