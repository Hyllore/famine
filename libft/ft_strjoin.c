/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/11/27 18:33:49 by amaindro          #+#    #+#             */
/*   Updated: 2016/01/11 22:00:40 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	*ft_strjoin(const char *s1, const char *s2)
{
	char	*s3;
	size_t	len;

	len = 0;
	if (s1 != NULL)
		len += ft_strlen(s1);
	if (s2 != NULL)
		len += ft_strlen(s2);
	s3 = ft_memalloc(sizeof(char) * (len + 1));
	if (!s3)
		return (NULL);
	if (s1 != NULL)
		ft_strcpy(s3, s1);
	if (s2 != NULL)
		ft_strcat(s3, s2);
	return (s3);
}
