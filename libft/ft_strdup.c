/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/11/23 11:43:02 by amaindro          #+#    #+#             */
/*   Updated: 2015/12/04 14:26:12 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "libft.h"

char	*ft_strdup(char *s1)
{
	char *s2;

	s2 = malloc(sizeof(*s1) * ft_strlen(s1) + 1);
	if (s2)
		return (ft_strcpy(s2, s1));
	return (NULL);
}
